"""
Report generation module for OSINT CLI Tool
"""

from tabulate import tabulate
from typing import Dict, List, Any
from osint_cli.utils.colors import Colors


class Reporter:
    """Report generation and formatting"""
    
    def __init__(self):
        self.colors = Colors()
    
    def print_email_report(self, results: Dict[str, Any]) -> None:
        """Print email investigation report"""
        print(f"\n{self.colors.CYAN}{'='*60}{self.colors.RESET}")
        print(f"{self.colors.CYAN}EMAIL INVESTIGATION REPORT{self.colors.RESET}")
        print(f"{self.colors.CYAN}{'='*60}{self.colors.RESET}")
        
        # Basic information
        print(f"\n{self.colors.YELLOW}Target Email:{self.colors.RESET} {results.get('email', 'N/A')}")
        print(f"{self.colors.YELLOW}Valid Format:{self.colors.RESET} {self._format_boolean(results.get('valid', False))}")
        print(f"{self.colors.YELLOW}Domain:{self.colors.RESET} {results.get('domain', 'N/A')}")
        print(f"{self.colors.YELLOW}Disposable Email:{self.colors.RESET} {self._format_boolean(results.get('disposable', False))}")
        print(f"{self.colors.YELLOW}Deliverable:{self.colors.RESET} {self._format_boolean(results.get('deliverable', False))}")
        
        # MX Records
        if results.get('mx_records'):
            print(f"\n{self.colors.YELLOW}MX Records:{self.colors.RESET}")
            for mx in results['mx_records']:
                print(f"  • {mx}")
        else:
            print(f"\n{self.colors.YELLOW}MX Records:{self.colors.RESET} None found")
        
        # Breach Data
        if results.get('breach_data'):
            print(f"\n{self.colors.RED}Data Breaches:{self.colors.RESET}")
            for breach in results['breach_data']:
                print(f"  • {breach.get('name', 'Unknown')} - {breach.get('date', 'Unknown date')}")
        else:
            print(f"\n{self.colors.GREEN}Data Breaches:{self.colors.RESET} No breaches found")
        
        # Social Media
        if results.get('social_media'):
            print(f"\n{self.colors.YELLOW}Social Media Presence:{self.colors.RESET}")
            social_data = []
            for platform, exists in results['social_media'].items():
                status = "✓" if exists else "✗"
                social_data.append([platform.title(), status])
            
            print(tabulate(social_data, headers=["Platform", "Exists"], tablefmt="grid"))
        
        # Investigation time
        if results.get('investigation_time'):
            print(f"\n{self.colors.BLUE}Investigation Time:{self.colors.RESET} {results['investigation_time']}s")
        
        # Error handling
        if results.get('error'):
            print(f"\n{self.colors.RED}Error:{self.colors.RESET} {results['error']}")
    
    def print_domain_report(self, results: Dict[str, Any]) -> None:
        """Print domain analysis report"""
        print(f"\n{self.colors.CYAN}{'='*60}{self.colors.RESET}")
        print(f"{self.colors.CYAN}DOMAIN ANALYSIS REPORT{self.colors.RESET}")
        print(f"{self.colors.CYAN}{'='*60}{self.colors.RESET}")
        
        # Basic information
        print(f"\n{self.colors.YELLOW}Target Domain:{self.colors.RESET} {results.get('domain', 'N/A')}")
        
        # IP Addresses
        if results.get('ip_addresses'):
            print(f"\n{self.colors.YELLOW}IP Addresses:{self.colors.RESET}")
            for ip in results['ip_addresses']:
                print(f"  • {ip}")
        else:
            print(f"\n{self.colors.YELLOW}IP Addresses:{self.colors.RESET} None found")
        
        # DNS Records
        if results.get('mx_records'):
            print(f"\n{self.colors.YELLOW}MX Records:{self.colors.RESET}")
            mx_data = []
            for mx in results['mx_records']:
                mx_data.append([mx.get('exchange', 'N/A'), mx.get('priority', 'N/A')])
            print(tabulate(mx_data, headers=["Exchange", "Priority"], tablefmt="grid"))
        
        if results.get('ns_records'):
            print(f"\n{self.colors.YELLOW}NS Records:{self.colors.RESET}")
            for ns in results['ns_records']:
                print(f"  • {ns}")
        
        if results.get('txt_records'):
            print(f"\n{self.colors.YELLOW}TXT Records:{self.colors.RESET}")
            for txt in results['txt_records']:
                print(f"  • {txt}")
        
        # WHOIS Data
        if results.get('whois_data'):
            print(f"\n{self.colors.YELLOW}WHOIS Information:{self.colors.RESET}")
            whois_data = results['whois_data']
            if not whois_data.get('error'):
                print(f"  Registrar: {whois_data.get('registrar', 'N/A')}")
                print(f"  Creation Date: {whois_data.get('creation_date', 'N/A')}")
                print(f"  Expiration Date: {whois_data.get('expiration_date', 'N/A')}")
                print(f"  Status: {whois_data.get('status', 'N/A')}")
            else:
                print(f"  Error: {whois_data.get('error', 'Unknown error')}")
        
        # Subdomains
        if results.get('subdomains'):
            print(f"\n{self.colors.YELLOW}Subdomains Found:{self.colors.RESET}")
            for subdomain in results['subdomains']:
                print(f"  • {subdomain}")
        else:
            print(f"\n{self.colors.YELLOW}Subdomains:{self.colors.RESET} None found")
        
        # SSL Information
        if results.get('ssl_info'):
            print(f"\n{self.colors.YELLOW}SSL Information:{self.colors.RESET}")
            ssl_info = results['ssl_info']
            if ssl_info:
                print(f"  Subject: {ssl_info.get('subject', {}).get('commonName', 'N/A')}")
                print(f"  Issuer: {ssl_info.get('issuer', {}).get('organizationName', 'N/A')}")
                print(f"  Valid From: {ssl_info.get('not_before', 'N/A')}")
                print(f"  Valid Until: {ssl_info.get('not_after', 'N/A')}")
        
        # Technologies
        if results.get('technologies'):
            print(f"\n{self.colors.YELLOW}Technologies Detected:{self.colors.RESET}")
            for tech in results['technologies']:
                print(f"  • {tech}")
        
        # Analysis time
        if results.get('analysis_time'):
            print(f"\n{self.colors.BLUE}Analysis Time:{self.colors.RESET} {results['analysis_time']}s")
        
        # Error handling
        if results.get('error'):
            print(f"\n{self.colors.RED}Error:{self.colors.RESET} {results['error']}")
    
    def print_ip_report(self, results: Dict[str, Any]) -> None:
        """Print IP investigation report"""
        print(f"\n{self.colors.CYAN}{'='*60}{self.colors.RESET}")
        print(f"{self.colors.CYAN}IP INVESTIGATION REPORT{self.colors.RESET}")
        print(f"{self.colors.CYAN}{'='*60}{self.colors.RESET}")
        
        # Basic information
        print(f"\n{self.colors.YELLOW}Target IP:{self.colors.RESET} {results.get('ip', 'N/A')}")
        print(f"{self.colors.YELLOW}Type:{self.colors.RESET} {results.get('type', 'N/A')}")
        print(f"{self.colors.YELLOW}Private:{self.colors.RESET} {self._format_boolean(results.get('is_private', False))}")
        print(f"{self.colors.YELLOW}Reserved:{self.colors.RESET} {self._format_boolean(results.get('is_reserved', False))}")
        
        # Geolocation
        if results.get('geolocation'):
            print(f"\n{self.colors.YELLOW}Geolocation:{self.colors.RESET}")
            geo = results['geolocation']
            print(f"  Country: {geo.get('country', 'N/A')} ({geo.get('country_code', 'N/A')})")
            print(f"  Region: {geo.get('region_name', 'N/A')}")
            print(f"  City: {geo.get('city', 'N/A')}")
            print(f"  ISP: {geo.get('isp', 'N/A')}")
            print(f"  Organization: {geo.get('org', 'N/A')}")
            print(f"  Timezone: {geo.get('timezone', 'N/A')}")
        
        # Reverse DNS
        if results.get('reverse_dns'):
            print(f"\n{self.colors.YELLOW}Reverse DNS:{self.colors.RESET}")
            for hostname in results['reverse_dns']:
                print(f"  • {hostname}")
        else:
            print(f"\n{self.colors.YELLOW}Reverse DNS:{self.colors.RESET} None found")
        
        # Open Ports
        if results.get('ports'):
            print(f"\n{self.colors.YELLOW}Open Ports:{self.colors.RESET}")
            port_data = []
            for port in results['ports']:
                port_data.append([port.get('port', 'N/A'), port.get('service', 'N/A'), port.get('status', 'N/A')])
            print(tabulate(port_data, headers=["Port", "Service", "Status"], tablefmt="grid"))
        else:
            print(f"\n{self.colors.YELLOW}Open Ports:{self.colors.RESET} None found")
        
        # Reputation
        if results.get('reputation'):
            print(f"\n{self.colors.YELLOW}Reputation Analysis:{self.colors.RESET}")
            rep = results['reputation']
            print(f"  Threat Score: {rep.get('threat_score', 0)}/100")
            print(f"  Malicious: {self._format_boolean(rep.get('is_malicious', False))}")
            print(f"  Tor Exit Node: {self._format_boolean(rep.get('is_tor_exit', False))}")
            print(f"  Proxy: {self._format_boolean(rep.get('is_proxy', False))}")
            print(f"  VPN: {self._format_boolean(rep.get('is_vpn', False))}")
            
            if rep.get('sources'):
                print(f"  Sources: {', '.join(rep['sources'])}")
        
        # Investigation time
        if results.get('investigation_time'):
            print(f"\n{self.colors.BLUE}Investigation Time:{self.colors.RESET} {results['investigation_time']}s")
        
        # Error handling
        if results.get('error'):
            print(f"\n{self.colors.RED}Error:{self.colors.RESET} {results['error']}")
    
    def print_social_report(self, results: Dict[str, Any]) -> None:
        """Print social media lookup report"""
        print(f"\n{self.colors.CYAN}{'='*60}{self.colors.RESET}")
        print(f"{self.colors.CYAN}SOCIAL MEDIA LOOKUP REPORT{self.colors.RESET}")
        print(f"{self.colors.CYAN}{'='*60}{self.colors.RESET}")
        
        # Basic information
        print(f"\n{self.colors.YELLOW}Target Username:{self.colors.RESET} {results.get('username', 'N/A')}")
        print(f"{self.colors.YELLOW}Total Platforms Found:{self.colors.RESET} {results.get('total_found', 0)}")
        
        # Platform results
        if results.get('platforms'):
            print(f"\n{self.colors.YELLOW}Platform Results:{self.colors.RESET}")
            platform_data = []
            for platform, data in results['platforms'].items():
                status = "✓" if data.get('exists', False) else "✗"
                response_time = f"{data.get('response_time', 0):.2f}s" if data.get('response_time') else "N/A"
                platform_data.append([platform.title(), status, response_time])
            
            print(tabulate(platform_data, headers=["Platform", "Exists", "Response Time"], tablefmt="grid"))
        
        # Lookup time
        if results.get('lookup_time'):
            print(f"\n{self.colors.BLUE}Lookup Time:{self.colors.RESET} {results['lookup_time']}s")
        
        # Error handling
        if results.get('error'):
            print(f"\n{self.colors.RED}Error:{self.colors.RESET} {results['error']}")
    
    def print_comprehensive_report(self, results: Dict[str, Any]) -> None:
        """Print comprehensive scan report"""
        print(f"\n{self.colors.CYAN}{'='*60}{self.colors.RESET}")
        print(f"{self.colors.CYAN}COMPREHENSIVE SCAN REPORT{self.colors.RESET}")
        print(f"{self.colors.CYAN}{'='*60}{self.colors.RESET}")
        
        # Print each type of report
        if 'email' in results:
            self.print_email_report(results['email'])
        
        if 'domain' in results:
            self.print_domain_report(results['domain'])
        
        if 'ip' in results:
            self.print_ip_report(results['ip'])
    
    def _format_boolean(self, value: bool) -> str:
        """Format boolean value with colors"""
        if value:
            return f"{self.colors.GREEN}Yes{self.colors.RESET}"
        else:
            return f"{self.colors.RED}No{self.colors.RESET}"
    
    def save_report(self, results: Dict[str, Any], filename: str) -> None:
        """Save report to file"""
        try:
            with open(filename, 'w') as f:
                # This is a simplified version - in a real implementation,
                # you would format the report properly for file output
                f.write(str(results))
            print(f"{self.colors.GREEN}Report saved to: {filename}{self.colors.RESET}")
        except Exception as e:
            print(f"{self.colors.RED}Error saving report: {str(e)}{self.colors.RESET}")