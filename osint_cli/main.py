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
from osint_cli.core.offline_cli import OfflineCLI
from osint_cli.utils.validators import validate_email, validate_domain, validate_ip
from osint_cli.utils.colors import Colors
from osint_cli.config import load_config, save_default_config


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
    # Decide offline mode via flags or config preferences
    def _prefer_offline() -> bool:
        if getattr(args, 'offline', False) is True:
            return True
        if getattr(args, 'online', False) is True:
            return False
        cfg = load_config(None)
        return bool(cfg.get('preferences', {}).get('prefer_offline', False))

    if _prefer_offline():
        try:
            from osint_cli.core.offline_intelligence import OfflineIntelligenceEngine
            engine = OfflineIntelligenceEngine()
            results = engine.analyze_email_intelligence(args.target)
            Reporter().print_comprehensive_report({'email': results})
            return 0
        except Exception as e:
            print(f"{Colors.RED}Offline analysis failed: {str(e)}{Colors.RESET}")
            return 1

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
    def _prefer_offline() -> bool:
        if getattr(args, 'offline', False) is True:
            return True
        if getattr(args, 'online', False) is True:
            return False
        cfg = load_config(None)
        return bool(cfg.get('preferences', {}).get('prefer_offline', False))

    if _prefer_offline():
        try:
            from osint_cli.core.offline_intelligence import OfflineIntelligenceEngine
            engine = OfflineIntelligenceEngine()
            results = engine.analyze_domain_intelligence(args.target)
            Reporter().print_comprehensive_report({'domain': results})
            return 0
        except Exception as e:
            print(f"{Colors.RED}Offline analysis failed: {str(e)}{Colors.RESET}")
            return 1

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
    def _prefer_offline() -> bool:
        if getattr(args, 'offline', False) is True:
            return True
        if getattr(args, 'online', False) is True:
            return False
        cfg = load_config(None)
        return bool(cfg.get('preferences', {}).get('prefer_offline', False))

    if _prefer_offline():
        try:
            from osint_cli.core.offline_intelligence import OfflineIntelligenceEngine
            engine = OfflineIntelligenceEngine()
            results = engine.analyze_ip_intelligence(args.target)
            Reporter().print_comprehensive_report({'ip': results})
            return 0
        except Exception as e:
            print(f"{Colors.RED}Offline analysis failed: {str(e)}{Colors.RESET}")
            return 1

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
    def _prefer_offline() -> bool:
        if getattr(args, 'offline', False) is True:
            return True
        if getattr(args, 'online', False) is True:
            return False
        cfg = load_config(None)
        return bool(cfg.get('preferences', {}).get('prefer_offline', False))

    if _prefer_offline():
        try:
            from osint_cli.core.offline_intelligence import OfflineIntelligenceEngine
            engine = OfflineIntelligenceEngine()
            results = engine.analyze_username_intelligence(args.username)
            Reporter().print_comprehensive_report({'username': results})
            return 0
        except Exception as e:
            print(f"{Colors.RED}Offline analysis failed: {str(e)}{Colors.RESET}")
            return 1

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
  osint-cli offline email --target user@example.com
  osint-cli offline domain --target example.com
  osint-cli offline correlate --targets user@example.com,example.com
        """
    )
    
    parser.add_argument(
        '--version', 
        action='version', 
        version='OSINT CLI Tool v2.0.0'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Email command
    email_parser = subparsers.add_parser('email', help='Investigate email address')
    email_parser.add_argument('--target', required=True, help='Email address to investigate')
    email_parser.add_argument('--online', action='store_true', help='Prefer live lookups when available')
    email_parser.add_argument('--offline', action='store_true', help='Force offline intelligence mode')
    email_parser.set_defaults(func=email_command)
    
    # Domain command
    domain_parser = subparsers.add_parser('domain', help='Analyze domain')
    domain_parser.add_argument('--target', required=True, help='Domain to analyze')
    domain_parser.add_argument('--online', action='store_true', help='Prefer live lookups when available')
    domain_parser.add_argument('--offline', action='store_true', help='Force offline intelligence mode')
    domain_parser.set_defaults(func=domain_command)
    
    # IP command
    ip_parser = subparsers.add_parser('ip', help='Investigate IP address')
    ip_parser.add_argument('--target', required=True, help='IP address to investigate')
    ip_parser.add_argument('--online', action='store_true', help='Prefer live lookups when available')
    ip_parser.add_argument('--offline', action='store_true', help='Force offline intelligence mode')
    ip_parser.set_defaults(func=ip_command)
    
    # Social media command
    social_parser = subparsers.add_parser('social', help='Lookup username on social media')
    social_parser.add_argument('--username', required=True, help='Username to lookup')
    social_parser.add_argument('--online', action='store_true', help='Prefer live checks when available')
    social_parser.add_argument('--offline', action='store_true', help='Analyze username offline')
    social_parser.set_defaults(func=social_command)
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Comprehensive scan')
    scan_parser.add_argument('--target', required=True, help='Target to scan')
    scan_parser.add_argument('--type', choices=['all', 'email', 'domain', 'ip'], 
                           default='all', help='Type of scan to perform')
    scan_parser.add_argument('--online', action='store_true', help='Prefer live lookups when available')
    scan_parser.add_argument('--offline', action='store_true', help='Force offline intelligence mode')
    scan_parser.set_defaults(func=scan_command)
    
    # Offline command
    offline_parser = subparsers.add_parser('offline', help='Offline intelligence analysis')
    offline_parser.add_argument('offline_args', nargs='*', help='Offline command arguments')
    offline_parser.set_defaults(func=offline_command)

    # Config command
    config_parser = subparsers.add_parser('config', help='Manage user configuration')
    config_parser.add_argument('--init', action='store_true', help='Initialize default config')
    config_parser.add_argument('--show', action='store_true', help='Show effective config')
    config_parser.add_argument('--path', help='Custom config path')
    config_parser.set_defaults(func=config_command)
    
    args = parser.parse_args()
    
    if not args.command:
        print_banner()
        parser.print_help()
        return 1
    
    return args.func(args)


def offline_command(args):
    """Handle offline intelligence commands"""
    offline_cli = OfflineCLI()
    return offline_cli.run(args.offline_args)


def config_command(args):
    """Manage user configuration (init/show)."""
    try:
        if getattr(args, 'init', False):
            path = save_default_config(args.path)
            print(f"{Colors.GREEN}Default config initialized at {path}{Colors.RESET}")
            return 0
        if getattr(args, 'show', False):
            cfg = load_config(args.path)
            import json as _json
            print(_json.dumps(cfg, indent=2))
            return 0
        # If neither provided, print help-like hint
        print(f"{Colors.YELLOW}Use --init to create default config or --show to display it.{Colors.RESET}")
        return 1
    except Exception as e:
        print(f"{Colors.RED}Config command failed: {str(e)}{Colors.RESET}")
        return 1


if __name__ == '__main__':
    sys.exit(main())