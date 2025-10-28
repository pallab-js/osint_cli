"""
Domain analysis module for OSINT CLI Tool
"""

import socket
import dns.resolver
import whois
import requests
from typing import Dict, List, Optional, Any
import time
from urllib.parse import urlparse


class DomainAnalyzer:
    """Domain analysis and reconnaissance"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'OSINT-CLI-Tool/1.0.0'
        })
    
    def analyze(self, domain: str) -> Dict[str, Any]:
        """
        Perform comprehensive domain analysis
        
        Args:
            domain: Domain name to analyze
            
        Returns:
            Dict containing analysis results
        """
        results = {
            'domain': domain,
            'ip_addresses': [],
            'mx_records': [],
            'ns_records': [],
            'txt_records': [],
            'whois_data': {},
            'subdomains': [],
            'ssl_info': {},
            'http_headers': {},
            'technologies': [],
            'analysis_time': None
        }
        
        start_time = time.time()
        
        try:
            # Clean domain
            clean_domain = self._clean_domain(domain)
            results['domain'] = clean_domain
            
            # Get IP addresses
            results['ip_addresses'] = self._get_ip_addresses(clean_domain)
            
            # Get DNS records
            results['mx_records'] = self._get_mx_records(clean_domain)
            results['ns_records'] = self._get_ns_records(clean_domain)
            results['txt_records'] = self._get_txt_records(clean_domain)
            
            # WHOIS lookup
            results['whois_data'] = self._get_whois_data(clean_domain)
            
            # Subdomain enumeration
            results['subdomains'] = self._enumerate_subdomains(clean_domain)
            
            # SSL/TLS information
            results['ssl_info'] = self._get_ssl_info(clean_domain)
            
            # HTTP headers
            results['http_headers'] = self._get_http_headers(clean_domain)
            
            # Technology detection
            results['technologies'] = self._detect_technologies(clean_domain)
            
            results['analysis_time'] = round(time.time() - start_time, 2)
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def _clean_domain(self, domain: str) -> str:
        """Clean and normalize domain name"""
        # Remove protocol
        if domain.startswith(('http://', 'https://')):
            domain = urlparse(domain).netloc
        
        # Remove www prefix
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # Remove trailing slash
        domain = domain.rstrip('/')
        
        return domain.lower()
    
    def _get_ip_addresses(self, domain: str) -> List[str]:
        """Get IP addresses for domain"""
        try:
            ip_addresses = socket.gethostbyname_ex(domain)[2]
            return [ip for ip in ip_addresses if not ip.startswith('127.')]
        except Exception:
            return []
    
    def _get_mx_records(self, domain: str) -> List[Dict[str, Any]]:
        """Get MX records for domain"""
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            return [
                {
                    'exchange': str(record.exchange),
                    'priority': record.preference
                }
                for record in mx_records
            ]
        except Exception:
            return []
    
    def _get_ns_records(self, domain: str) -> List[str]:
        """Get NS records for domain"""
        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            return [str(record) for record in ns_records]
        except Exception:
            return []
    
    def _get_txt_records(self, domain: str) -> List[str]:
        """Get TXT records for domain"""
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT')
            return [str(record).strip('"') for record in txt_records]
        except Exception:
            return []
    
    def _get_whois_data(self, domain: str) -> Dict[str, Any]:
        """Get WHOIS data for domain"""
        try:
            whois_info = whois.whois(domain)
            
            # Convert to dictionary and clean up
            whois_dict = {}
            
            if hasattr(whois_info, 'domain_name'):
                whois_dict['domain_name'] = str(whois_info.domain_name)
            
            if hasattr(whois_info, 'registrar'):
                whois_dict['registrar'] = str(whois_info.registrar)
            
            if hasattr(whois_info, 'creation_date'):
                whois_dict['creation_date'] = str(whois_info.creation_date)
            
            if hasattr(whois_info, 'expiration_date'):
                whois_dict['expiration_date'] = str(whois_info.expiration_date)
            
            if hasattr(whois_info, 'name_servers'):
                whois_dict['name_servers'] = [str(ns) for ns in whois_info.name_servers]
            
            if hasattr(whois_info, 'status'):
                whois_dict['status'] = str(whois_info.status)
            
            return whois_dict
            
        except Exception as e:
            return {'error': str(e)}
    
    def _enumerate_subdomains(self, domain: str) -> List[str]:
        """Enumerate common subdomains"""
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'api', 'blog', 'shop',
            'support', 'help', 'docs', 'dev', 'test', 'staging',
            'app', 'mobile', 'cdn', 'static', 'assets', 'img',
            'images', 'css', 'js', 'files', 'download', 'upload'
        ]
        
        found_subdomains = []
        
        for subdomain in common_subdomains:
            try:
                full_domain = f"{subdomain}.{domain}"
                socket.gethostbyname(full_domain)
                found_subdomains.append(full_domain)
            except Exception:
                continue
        
        return found_subdomains
    
    def _get_ssl_info(self, domain: str) -> Dict[str, Any]:
        """Get SSL/TLS information"""
        try:
            import ssl
            import socket
            
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    return {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'subject_alt_name': cert.get('subjectAltName', [])
                    }
        except Exception:
            return {}
    
    def _get_http_headers(self, domain: str) -> Dict[str, str]:
        """Get HTTP headers"""
        try:
            url = f"https://{domain}"
            response = self.session.head(url, timeout=10, allow_redirects=True)
            return dict(response.headers)
        except Exception:
            try:
                url = f"http://{domain}"
                response = self.session.head(url, timeout=10, allow_redirects=True)
                return dict(response.headers)
            except Exception:
                return {}
    
    def _detect_technologies(self, domain: str) -> List[str]:
        """Detect web technologies"""
        technologies = []
        
        try:
            url = f"https://{domain}"
            response = self.session.get(url, timeout=10)
            headers = response.headers
            
            # Check for common technologies
            if 'server' in headers:
                technologies.append(f"Server: {headers['server']}")
            
            if 'x-powered-by' in headers:
                technologies.append(f"Powered by: {headers['x-powered-by']}")
            
            if 'x-aspnet-version' in headers:
                technologies.append("ASP.NET")
            
            if 'x-drupal-cache' in headers:
                technologies.append("Drupal")
            
            if 'x-generator' in headers:
                technologies.append(f"Generator: {headers['x-generator']}")
            
            # Check response content for frameworks
            content = response.text.lower()
            if 'wordpress' in content:
                technologies.append("WordPress")
            elif 'drupal' in content:
                technologies.append("Drupal")
            elif 'joomla' in content:
                technologies.append("Joomla")
            
        except Exception:
            pass
        
        return technologies