"""
IP address investigation module for OSINT CLI Tool
"""

import socket
import requests
import json
from typing import Dict, List, Optional, Any
import time
import ipaddress


class IPInvestigator:
    """IP address investigation and analysis"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'OSINT-CLI-Tool/1.0.0'
        })
    
    def investigate(self, ip: str) -> Dict[str, Any]:
        """
        Perform comprehensive IP investigation
        
        Args:
            ip: IP address to investigate
            
        Returns:
            Dict containing investigation results
        """
        results = {
            'ip': ip,
            'type': '',
            'is_private': False,
            'is_reserved': False,
            'geolocation': {},
            'reverse_dns': [],
            'ports': [],
            'whois_data': {},
            'reputation': {},
            'investigation_time': None
        }
        
        start_time = time.time()
        
        try:
            # Validate IP
            ip_obj = ipaddress.ip_address(ip)
            results['type'] = 'IPv4' if isinstance(ip_obj, ipaddress.IPv4Address) else 'IPv6'
            results['is_private'] = ip_obj.is_private
            results['is_reserved'] = ip_obj.is_reserved
            
            # Geolocation
            results['geolocation'] = self._get_geolocation(ip)
            
            # Reverse DNS lookup
            results['reverse_dns'] = self._get_reverse_dns(ip)
            
            # Port scanning (common ports)
            results['ports'] = self._scan_ports(ip)
            
            # WHOIS data
            results['whois_data'] = self._get_whois_data(ip)
            
            # Reputation check
            results['reputation'] = self._check_reputation(ip)
            
            results['investigation_time'] = round(time.time() - start_time, 2)
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def _get_geolocation(self, ip: str) -> Dict[str, Any]:
        """Get geolocation information for IP"""
        try:
            # Using ip-api.com (free service)
            response = self.session.get(f"http://ip-api.com/json/{ip}", timeout=10)
            data = response.json()
            
            if data.get('status') == 'success':
                return {
                    'country': data.get('country', ''),
                    'country_code': data.get('countryCode', ''),
                    'region': data.get('region', ''),
                    'region_name': data.get('regionName', ''),
                    'city': data.get('city', ''),
                    'zip': data.get('zip', ''),
                    'lat': data.get('lat', 0),
                    'lon': data.get('lon', 0),
                    'timezone': data.get('timezone', ''),
                    'isp': data.get('isp', ''),
                    'org': data.get('org', ''),
                    'as': data.get('as', ''),
                    'query': data.get('query', '')
                }
        except Exception:
            pass
        
        return {}
    
    def _get_reverse_dns(self, ip: str) -> List[str]:
        """Get reverse DNS records for IP"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return [hostname]
        except Exception:
            return []
    
    def _scan_ports(self, ip: str, timeout: float = 1.0) -> List[Dict[str, Any]]:
        """Scan common ports on IP"""
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306
        ]
        
        open_ports = []
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    service = self._get_service_name(port)
                    open_ports.append({
                        'port': port,
                        'service': service,
                        'status': 'open'
                    })
            except Exception:
                continue
        
        return open_ports
    
    def _get_service_name(self, port: int) -> str:
        """Get service name for common ports"""
        services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAPS',
            995: 'POP3S',
            3389: 'RDP',
            5432: 'PostgreSQL',
            3306: 'MySQL'
        }
        return services.get(port, 'Unknown')
    
    def _get_whois_data(self, ip: str) -> Dict[str, Any]:
        """Get WHOIS data for IP"""
        try:
            # This is a simplified WHOIS lookup
            # In a real implementation, you would use a proper WHOIS library
            return {
                'netname': 'Unknown',
                'descr': 'No description available',
                'country': 'Unknown',
                'admin_c': 'Unknown',
                'tech_c': 'Unknown',
                'status': 'Unknown'
            }
        except Exception:
            return {}
    
    def _check_reputation(self, ip: str) -> Dict[str, Any]:
        """Check IP reputation"""
        reputation = {
            'is_malicious': False,
            'is_tor_exit': False,
            'is_proxy': False,
            'is_vpn': False,
            'threat_score': 0,
            'sources': []
        }
        
        try:
            # Check if IP is in Tor exit node list
            reputation['is_tor_exit'] = self._check_tor_exit_node(ip)
            
            # Check if IP is a known proxy/VPN
            reputation['is_proxy'] = self._check_proxy(ip)
            reputation['is_vpn'] = self._check_vpn(ip)
            
            # Calculate threat score
            threat_score = 0
            if reputation['is_tor_exit']:
                threat_score += 30
                reputation['sources'].append('Tor Exit Node')
            
            if reputation['is_proxy']:
                threat_score += 20
                reputation['sources'].append('Proxy')
            
            if reputation['is_vpn']:
                threat_score += 15
                reputation['sources'].append('VPN')
            
            reputation['threat_score'] = min(threat_score, 100)
            reputation['is_malicious'] = threat_score > 50
            
        except Exception:
            pass
        
        return reputation
    
    def _check_tor_exit_node(self, ip: str) -> bool:
        """Check if IP is a Tor exit node"""
        try:
            # This is a simplified check
            # In a real implementation, you would check against Tor exit node lists
            return False
        except Exception:
            return False
    
    def _check_proxy(self, ip: str) -> bool:
        """Check if IP is a known proxy"""
        try:
            # This is a simplified check
            # In a real implementation, you would check against proxy databases
            return False
        except Exception:
            return False
    
    def _check_vpn(self, ip: str) -> bool:
        """Check if IP is a known VPN"""
        try:
            # This is a simplified check
            # In a real implementation, you would check against VPN databases
            return False
        except Exception:
            return False
    
    def get_ip_info(self, ip: str) -> Dict[str, Any]:
        """Get basic IP information"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return {
                'version': ip_obj.version,
                'is_private': ip_obj.is_private,
                'is_reserved': ip_obj.is_reserved,
                'is_loopback': ip_obj.is_loopback,
                'is_multicast': ip_obj.is_multicast,
                'is_link_local': ip_obj.is_link_local,
                'is_global': ip_obj.is_global
            }
        except Exception:
            return {}