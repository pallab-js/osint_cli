#!/usr/bin/env python3
"""
Main entry point for OSINT CLI Tool
"""

import argparse
import sys
from typing import Optional

from osint_cli.core.email_investigator import EmailInvestigator
from osint_cli.core.domain_analyzer import DomainAnalyzer
from osint_cli.core.ip_investigator import IPInvestigator
from osint_cli.core.social_media_lookup import SocialMediaLookup
from osint_cli.core.reporter import Reporter
from osint_cli.utils.validators import validate_email, validate_domain, validate_ip
from osint_cli.utils.colors import Colors


def print_banner():
    """Print the tool banner"""
    banner = f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════════╗
║                    OSINT CLI Tool v1.0.0                    ║
║              Open Source Intelligence Gathering             ║
╚══════════════════════════════════════════════════════════════╝{Colors.RESET}
"""
    print(banner)


def email_command(args):
    """Handle email investigation command"""
    if not validate_email(args.target):
        print(f"{Colors.RED}Error: Invalid email address format{Colors.RESET}")
        return 1
    
    print(f"{Colors.YELLOW}Investigating email: {args.target}{Colors.RESET}")
    
    investigator = EmailInvestigator()
    reporter = Reporter()
    
    try:
        results = investigator.investigate(args.target)
        reporter.print_email_report(results)
        return 0
    except Exception as e:
        print(f"{Colors.RED}Error during email investigation: {str(e)}{Colors.RESET}")
        return 1


def domain_command(args):
    """Handle domain analysis command"""
    if not validate_domain(args.target):
        print(f"{Colors.RED}Error: Invalid domain format{Colors.RESET}")
        return 1
    
    print(f"{Colors.YELLOW}Analyzing domain: {args.target}{Colors.RESET}")
    
    analyzer = DomainAnalyzer()
    reporter = Reporter()
    
    try:
        results = analyzer.analyze(args.target)
        reporter.print_domain_report(results)
        return 0
    except Exception as e:
        print(f"{Colors.RED}Error during domain analysis: {str(e)}{Colors.RESET}")
        return 1


def ip_command(args):
    """Handle IP investigation command"""
    if not validate_ip(args.target):
        print(f"{Colors.RED}Error: Invalid IP address format{Colors.RESET}")
        return 1
    
    print(f"{Colors.YELLOW}Investigating IP: {args.target}{Colors.RESET}")
    
    investigator = IPInvestigator()
    reporter = Reporter()
    
    try:
        results = investigator.investigate(args.target)
        reporter.print_ip_report(results)
        return 0
    except Exception as e:
        print(f"{Colors.RED}Error during IP investigation: {str(e)}{Colors.RESET}")
        return 1


def social_command(args):
    """Handle social media lookup command"""
    print(f"{Colors.YELLOW}Looking up username: {args.username}{Colors.RESET}")
    
    lookup = SocialMediaLookup()
    reporter = Reporter()
    
    try:
        results = lookup.lookup_username(args.username)
        reporter.print_social_report(results)
        return 0
    except Exception as e:
        print(f"{Colors.RED}Error during social media lookup: {str(e)}{Colors.RESET}")
        return 1


def scan_command(args):
    """Handle comprehensive scan command"""
    print(f"{Colors.YELLOW}Performing comprehensive scan on: {args.target}{Colors.RESET}")
    
    reporter = Reporter()
    results = {}
    
    try:
        # Determine scan type based on target
        if validate_email(args.target):
            investigator = EmailInvestigator()
            results['email'] = investigator.investigate(args.target)
        elif validate_domain(args.target):
            analyzer = DomainAnalyzer()
            results['domain'] = analyzer.analyze(args.target)
        elif validate_ip(args.target):
            investigator = IPInvestigator()
            results['ip'] = investigator.investigate(args.target)
        else:
            print(f"{Colors.RED}Error: Invalid target format{Colors.RESET}")
            return 1
        
        reporter.print_comprehensive_report(results)
        return 0
    except Exception as e:
        print(f"{Colors.RED}Error during comprehensive scan: {str(e)}{Colors.RESET}")
        return 1


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="OSINT CLI Tool - Open Source Intelligence Gathering",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  osint-cli email --target user@example.com
  osint-cli domain --target example.com
  osint-cli ip --target 8.8.8.8
  osint-cli social --username john_doe
  osint-cli scan --target example.com
        """
    )
    
    parser.add_argument(
        '--version', 
        action='version', 
        version='OSINT CLI Tool v1.0.0'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Email command
    email_parser = subparsers.add_parser('email', help='Investigate email address')
    email_parser.add_argument('--target', required=True, help='Email address to investigate')
    email_parser.set_defaults(func=email_command)
    
    # Domain command
    domain_parser = subparsers.add_parser('domain', help='Analyze domain')
    domain_parser.add_argument('--target', required=True, help='Domain to analyze')
    domain_parser.set_defaults(func=domain_command)
    
    # IP command
    ip_parser = subparsers.add_parser('ip', help='Investigate IP address')
    ip_parser.add_argument('--target', required=True, help='IP address to investigate')
    ip_parser.set_defaults(func=ip_command)
    
    # Social media command
    social_parser = subparsers.add_parser('social', help='Lookup username on social media')
    social_parser.add_argument('--username', required=True, help='Username to lookup')
    social_parser.set_defaults(func=social_command)
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Comprehensive scan')
    scan_parser.add_argument('--target', required=True, help='Target to scan')
    scan_parser.add_argument('--type', choices=['all', 'email', 'domain', 'ip'], 
                           default='all', help='Type of scan to perform')
    scan_parser.set_defaults(func=scan_command)
    
    args = parser.parse_args()
    
    if not args.command:
        print_banner()
        parser.print_help()
        return 1
    
    return args.func(args)


if __name__ == '__main__':
    sys.exit(main())