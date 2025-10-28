"""
Social media lookup module for OSINT CLI Tool
"""

import requests
from typing import Dict, List, Optional, Any
import time
import re


class SocialMediaLookup:
    """Social media username lookup and analysis"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
    
    def lookup_username(self, username: str) -> Dict[str, Any]:
        """
        Lookup username across social media platforms
        
        Args:
            username: Username to lookup
            
        Returns:
            Dict containing lookup results
        """
        results = {
            'username': username,
            'platforms': {},
            'total_found': 0,
            'lookup_time': None
        }
        
        start_time = time.time()
        
        try:
            # Clean username
            clean_username = self._clean_username(username)
            results['username'] = clean_username
            
            # Define platforms to check
            platforms = {
                'twitter': f'https://twitter.com/{clean_username}',
                'instagram': f'https://instagram.com/{clean_username}',
                'facebook': f'https://facebook.com/{clean_username}',
                'linkedin': f'https://linkedin.com/in/{clean_username}',
                'github': f'https://github.com/{clean_username}',
                'reddit': f'https://reddit.com/user/{clean_username}',
                'youtube': f'https://youtube.com/@{clean_username}',
                'tiktok': f'https://tiktok.com/@{clean_username}',
                'snapchat': f'https://snapchat.com/add/{clean_username}',
                'twitch': f'https://twitch.tv/{clean_username}',
                'discord': f'https://discord.com/users/{clean_username}',
                'telegram': f'https://t.me/{clean_username}'
            }
            
            # Check each platform
            for platform, url in platforms.items():
                try:
                    platform_result = self._check_platform(platform, url, clean_username)
                    results['platforms'][platform] = platform_result
                    
                    if platform_result['exists']:
                        results['total_found'] += 1
                        
                except Exception as e:
                    results['platforms'][platform] = {
                        'exists': False,
                        'url': url,
                        'error': str(e)
                    }
            
            results['lookup_time'] = round(time.time() - start_time, 2)
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def _clean_username(self, username: str) -> str:
        """Clean and normalize username"""
        # Remove @ symbol if present
        username = username.lstrip('@')
        
        # Remove spaces and special characters that might cause issues
        username = re.sub(r'[^\w.-]', '', username)
        
        # Ensure username is not empty
        if not username:
            username = 'invalid'
        
        return username
    
    def _check_platform(self, platform: str, url: str, username: str) -> Dict[str, Any]:
        """Check if username exists on specific platform"""
        result = {
            'exists': False,
            'url': url,
            'status_code': None,
            'response_time': 0,
            'profile_info': {}
        }
        
        start_time = time.time()
        
        try:
            response = self.session.head(url, timeout=10, allow_redirects=True)
            result['status_code'] = response.status_code
            result['response_time'] = round(time.time() - start_time, 2)
            
            # Check if profile exists based on status code and platform
            if self._is_profile_exists(platform, response):
                result['exists'] = True
                result['profile_info'] = self._extract_profile_info(platform, response)
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _is_profile_exists(self, platform: str, response: requests.Response) -> bool:
        """Determine if profile exists based on response"""
        status_code = response.status_code
        
        if platform in ['twitter', 'instagram', 'github', 'reddit', 'youtube', 'tiktok', 'twitch']:
            return status_code == 200
        elif platform in ['facebook', 'linkedin']:
            # These platforms often return 200 even for non-existent profiles
            return status_code == 200 and 'not found' not in response.text.lower()
        elif platform in ['snapchat', 'discord', 'telegram']:
            # These platforms have different behavior
            return status_code == 200
        else:
            return status_code == 200
    
    def _extract_profile_info(self, platform: str, response: requests.Response) -> Dict[str, Any]:
        """Extract profile information from response"""
        profile_info = {}
        
        try:
            # Get response text for analysis
            text = response.text.lower()
            
            # Platform-specific information extraction
            if platform == 'twitter':
                if 'verified' in text:
                    profile_info['verified'] = True
                if 'protected' in text:
                    profile_info['protected'] = True
            
            elif platform == 'instagram':
                if 'verified' in text:
                    profile_info['verified'] = True
                if 'private' in text:
                    profile_info['private'] = True
            
            elif platform == 'github':
                if 'followers' in text:
                    profile_info['has_followers'] = True
                if 'repositories' in text:
                    profile_info['has_repositories'] = True
            
            elif platform == 'reddit':
                if 'karma' in text:
                    profile_info['has_karma'] = True
                if 'cake day' in text:
                    profile_info['has_cake_day'] = True
            
        except Exception:
            pass
        
        return profile_info
    
    def get_username_suggestions(self, username: str) -> List[str]:
        """Get username suggestions based on common variations"""
        suggestions = []
        
        # Add common variations
        variations = [
            username,
            f"{username}_",
            f"_{username}",
            f"{username}1",
            f"{username}2",
            f"{username}3",
            f"{username}123",
            f"{username}2024",
            f"{username}2023",
            f"real{username}",
            f"official{username}",
            f"{username}official"
        ]
        
        # Remove duplicates while preserving order
        seen = set()
        for variation in variations:
            if variation not in seen:
                suggestions.append(variation)
                seen.add(variation)
        
        return suggestions[:10]  # Limit to 10 suggestions
    
    def analyze_username_pattern(self, username: str) -> Dict[str, Any]:
        """Analyze username pattern and characteristics"""
        analysis = {
            'length': len(username),
            'has_numbers': bool(re.search(r'\d', username)),
            'has_underscores': '_' in username,
            'has_dots': '.' in username,
            'has_hyphens': '-' in username,
            'is_all_lowercase': username.islower(),
            'is_all_uppercase': username.isupper(),
            'has_mixed_case': username != username.lower() and username != username.upper(),
            'starts_with_number': username[0].isdigit() if username else False,
            'ends_with_number': username[-1].isdigit() if username else False,
            'common_patterns': []
        }
        
        # Check for common patterns
        if re.match(r'^[a-zA-Z]+\d+$', username):
            analysis['common_patterns'].append('name_numbers')
        
        if re.match(r'^\d+[a-zA-Z]+$', username):
            analysis['common_patterns'].append('numbers_name')
        
        if re.match(r'^[a-zA-Z]+_[a-zA-Z]+$', username):
            analysis['common_patterns'].append('name_underscore_name')
        
        if re.match(r'^[a-zA-Z]+\.[a-zA-Z]+$', username):
            analysis['common_patterns'].append('name_dot_name')
        
        return analysis