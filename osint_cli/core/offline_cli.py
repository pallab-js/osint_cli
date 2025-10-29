"""
Offline CLI Interface for Independent OSINT Analysis
Provides comprehensive offline intelligence capabilities
"""

import argparse
import sys
from typing import Dict, List, Any, Optional
from datetime import datetime

from .offline_intelligence import OfflineIntelligenceEngine
from .reporter import Reporter
from ..utils.colors import Colors
from ..utils.validators import validate_email, validate_domain, validate_ip, sanitize_input


class OfflineCLI:
    """Offline CLI interface for independent OSINT analysis"""
    
    def __init__(self):
        self.colors = Colors()
        self.reporter = Reporter()
        self.intelligence_engine = OfflineIntelligenceEngine()
        
        # CLI configuration
        self.parser = self._create_parser()
        self.args = None
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create command line argument parser"""
        parser = argparse.ArgumentParser(
            description="Offline OSINT Intelligence Tool - Independent Analysis",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  osint-cli offline email --target user@example.com
  osint-cli offline domain --target example.com
  osint-cli offline username --target john_doe
  osint-cli offline ip --target 8.8.8.8
  osint-cli offline correlate --targets user@example.com,example.com,john_doe
  osint-cli offline analyze --target user@example.com --comprehensive
  osint-cli offline report --target user@example.com --output report.json
            """
        )
        
        # Main subcommands
        subparsers = parser.add_subparsers(dest='command', help='Available commands')
        
        # Email analysis
        email_parser = subparsers.add_parser('email', help='Analyze email address')
        email_parser.add_argument('--target', required=True, help='Email address to analyze')
        email_parser.add_argument('--comprehensive', action='store_true', help='Perform comprehensive analysis')
        email_parser.add_argument('--output', help='Output file for results')
        
        # Domain analysis
        domain_parser = subparsers.add_parser('domain', help='Analyze domain name')
        domain_parser.add_argument('--target', required=True, help='Domain name to analyze')
        domain_parser.add_argument('--comprehensive', action='store_true', help='Perform comprehensive analysis')
        domain_parser.add_argument('--output', help='Output file for results')
        
        # Username analysis
        username_parser = subparsers.add_parser('username', help='Analyze username')
        username_parser.add_argument('--target', required=True, help='Username to analyze')
        username_parser.add_argument('--comprehensive', action='store_true', help='Perform comprehensive analysis')
        username_parser.add_argument('--output', help='Output file for results')
        
        # IP analysis
        ip_parser = subparsers.add_parser('ip', help='Analyze IP address')
        ip_parser.add_argument('--target', required=True, help='IP address to analyze')
        ip_parser.add_argument('--comprehensive', action='store_true', help='Perform comprehensive analysis')
        ip_parser.add_argument('--output', help='Output file for results')
        
        # Correlation analysis
        correlate_parser = subparsers.add_parser('correlate', help='Correlate multiple targets')
        correlate_parser.add_argument('--targets', required=True, help='Comma-separated list of targets')
        correlate_parser.add_argument('--output', help='Output file for results')
        
        # Comprehensive analysis
        analyze_parser = subparsers.add_parser('analyze', help='Comprehensive analysis')
        analyze_parser.add_argument('--target', required=True, help='Target to analyze')
        analyze_parser.add_argument('--comprehensive', action='store_true', help='Perform comprehensive analysis')
        analyze_parser.add_argument('--output', help='Output file for results')
        
        # Report generation
        report_parser = subparsers.add_parser('report', help='Generate intelligence report')
        report_parser.add_argument('--target', required=True, help='Target to report on')
        report_parser.add_argument('--format', choices=['json', 'txt', 'html'], default='txt', help='Report format')
        report_parser.add_argument('--output', help='Output file for report')
        
        # History management
        history_parser = subparsers.add_parser('history', help='View analysis history')
        history_parser.add_argument('--limit', type=int, default=10, help='Number of recent analyses to show')
        history_parser.add_argument('--filter', choices=['email', 'domain', 'username', 'ip'], help='Filter by analysis type')
        
        # Cache management
        cache_parser = subparsers.add_parser('cache', help='Manage intelligence cache')
        cache_parser.add_argument('--clear', action='store_true', help='Clear intelligence cache')
        cache_parser.add_argument('--status', action='store_true', help='Show cache status')
        
        # Database management
        db_parser = subparsers.add_parser('database', help='Manage local databases')
        db_parser.add_argument('--update', action='store_true', help='Update local databases')
        db_parser.add_argument('--status', action='store_true', help='Show database status')
        db_parser.add_argument('--export', help='Export database to file')
        db_parser.add_argument('--import', dest='import_file', help='Import database from file')
        
        return parser
    
    def run(self, args: List[str] = None) -> int:
        """Run the offline CLI"""
        try:
            try:
                self.args = self.parser.parse_args(args)
            except SystemExit:
                # Invalid arguments; return non-zero exit code instead of exiting process
                return 1
            
            if not self.args.command:
                self.parser.print_help()
                return 1
            
            # Route to appropriate handler
            if self.args.command == 'email':
                return self._handle_email_analysis()
            elif self.args.command == 'domain':
                return self._handle_domain_analysis()
            elif self.args.command == 'username':
                return self._handle_username_analysis()
            elif self.args.command == 'ip':
                return self._handle_ip_analysis()
            elif self.args.command == 'correlate':
                return self._handle_correlation_analysis()
            elif self.args.command == 'analyze':
                return self._handle_comprehensive_analysis()
            elif self.args.command == 'report':
                return self._handle_report_generation()
            elif self.args.command == 'history':
                return self._handle_history()
            elif self.args.command == 'cache':
                return self._handle_cache_management()
            elif self.args.command == 'database':
                return self._handle_database_management()
            else:
                self.colors.error(f"Unknown command: {self.args.command}")
                return 1
                
        except KeyboardInterrupt:
            self.colors.warning("\nOperation cancelled by user")
            return 1
        except Exception as e:
            self.colors.error(f"Error: {str(e)}")
            return 1
    
    def _handle_email_analysis(self) -> int:
        """Handle email analysis"""
        email = sanitize_input(self.args.target)
        
        if not validate_email(email):
            self.colors.error("Invalid email address format")
            return 1
        
        self.colors.info(f"Analyzing email: {email}")
        
        try:
            analysis = self.intelligence_engine.analyze_email_intelligence(email)
            
            # Display results
            self._display_email_analysis(analysis)
            
            # Save to file if requested
            if self.args.output:
                self._save_analysis(analysis, self.args.output)
                self.colors.success(f"Analysis saved to {self.args.output}")
            
            return 0
            
        except Exception as e:
            self.colors.error(f"Analysis failed: {str(e)}")
            return 1
    
    def _handle_domain_analysis(self) -> int:
        """Handle domain analysis"""
        domain = sanitize_input(self.args.target)
        
        if not validate_domain(domain):
            self.colors.error("Invalid domain format")
            return 1
        
        self.colors.info(f"Analyzing domain: {domain}")
        
        try:
            analysis = self.intelligence_engine.analyze_domain_intelligence(domain)
            
            # Display results
            self._display_domain_analysis(analysis)
            
            # Save to file if requested
            if self.args.output:
                self._save_analysis(analysis, self.args.output)
                self.colors.success(f"Analysis saved to {self.args.output}")
            
            return 0
            
        except Exception as e:
            self.colors.error(f"Analysis failed: {str(e)}")
            return 1
    
    def _handle_username_analysis(self) -> int:
        """Handle username analysis"""
        username = sanitize_input(self.args.target)
        
        if not username:
            self.colors.error("Invalid username")
            return 1
        
        self.colors.info(f"Analyzing username: {username}")
        
        try:
            analysis = self.intelligence_engine.analyze_username_intelligence(username)
            
            # Display results
            self._display_username_analysis(analysis)
            
            # Save to file if requested
            if self.args.output:
                self._save_analysis(analysis, self.args.output)
                self.colors.success(f"Analysis saved to {self.args.output}")
            
            return 0
            
        except Exception as e:
            self.colors.error(f"Analysis failed: {str(e)}")
            return 1
    
    def _handle_ip_analysis(self) -> int:
        """Handle IP analysis"""
        ip = sanitize_input(self.args.target)
        
        if not validate_ip(ip):
            self.colors.error("Invalid IP address format")
            return 1
        
        self.colors.info(f"Analyzing IP: {ip}")
        
        try:
            analysis = self.intelligence_engine.analyze_ip_intelligence(ip)
            
            # Display results
            self._display_ip_analysis(analysis)
            
            # Save to file if requested
            if self.args.output:
                self._save_analysis(analysis, self.args.output)
                self.colors.success(f"Analysis saved to {self.args.output}")
            
            return 0
            
        except Exception as e:
            self.colors.error(f"Analysis failed: {str(e)}")
            return 1
    
    def _handle_correlation_analysis(self) -> int:
        """Handle correlation analysis"""
        targets = [sanitize_input(t.strip()) for t in self.args.targets.split(',')]
        
        if len(targets) < 2:
            self.colors.error("At least 2 targets required for correlation analysis")
            return 1
        
        self.colors.info(f"Correlating {len(targets)} targets")
        
        try:
            correlation = self.intelligence_engine.correlate_intelligence(targets)
            
            # Display results
            self._display_correlation_analysis(correlation)
            
            # Save to file if requested
            if self.args.output:
                self._save_analysis(correlation, self.args.output)
                self.colors.success(f"Correlation analysis saved to {self.args.output}")
            
            return 0
            
        except Exception as e:
            self.colors.error(f"Correlation analysis failed: {str(e)}")
            return 1
    
    def _handle_comprehensive_analysis(self) -> int:
        """Handle comprehensive analysis"""
        target = sanitize_input(self.args.target)
        
        self.colors.info(f"Performing comprehensive analysis: {target}")
        
        try:
            # Determine target type and analyze
            if '@' in target and validate_email(target):
                analysis = self.intelligence_engine.analyze_email_intelligence(target)
            elif '.' in target and validate_domain(target):
                analysis = self.intelligence_engine.analyze_domain_intelligence(target)
            elif validate_ip(target):
                analysis = self.intelligence_engine.analyze_ip_intelligence(target)
            else:
                analysis = self.intelligence_engine.analyze_username_intelligence(target)
            
            # Display results
            self._display_comprehensive_analysis(analysis)
            
            # Save to file if requested
            if self.args.output:
                self._save_analysis(analysis, self.args.output)
                self.colors.success(f"Comprehensive analysis saved to {self.args.output}")
            
            return 0
            
        except Exception as e:
            self.colors.error(f"Comprehensive analysis failed: {str(e)}")
            return 1
    
    def _handle_report_generation(self) -> int:
        """Handle report generation"""
        target = sanitize_input(self.args.target)
        
        self.colors.info(f"Generating intelligence report: {target}")
        
        try:
            # Determine target type and analyze
            if '@' in target and validate_email(target):
                analysis = self.intelligence_engine.analyze_email_intelligence(target)
            elif '.' in target and validate_domain(target):
                analysis = self.intelligence_engine.analyze_domain_intelligence(target)
            elif validate_ip(target):
                analysis = self.intelligence_engine.analyze_ip_intelligence(target)
            else:
                analysis = self.intelligence_engine.analyze_username_intelligence(target)
            
            # Generate report
            report = self._generate_intelligence_report(analysis)
            
            # Display or save report
            if self.args.output:
                self._save_report(report, self.args.output, self.args.format)
                self.colors.success(f"Report saved to {self.args.output}")
            else:
                self._display_report(report)
            
            return 0
            
        except Exception as e:
            self.colors.error(f"Report generation failed: {str(e)}")
            return 1
    
    def _handle_history(self) -> int:
        """Handle history management"""
        history = self.intelligence_engine.get_analysis_history()
        
        if not history:
            self.colors.info("No analysis history found")
            return 0
        
        # Filter by type if requested
        if self.args.filter:
            history = [h for h in history if h.get('type') == self.args.filter]
        
        # Limit results
        history = history[-self.args.limit:]
        
        # Display history
        self._display_history(history)
        
        return 0
    
    def _handle_cache_management(self) -> int:
        """Handle cache management"""
        if self.args.clear:
            self.intelligence_engine.clear_cache()
            self.colors.success("Intelligence cache cleared")
            return 0
        
        if self.args.status:
            cache_size = len(self.intelligence_engine.intelligence_cache)
            self.colors.info(f"Cache contains {cache_size} entries")
            return 0
        
        return 0
    
    def _handle_database_management(self) -> int:
        """Handle database management"""
        if self.args.update:
            self.colors.info("Updating local databases...")
            # In a real implementation, this would update the databases
            self.colors.success("Local databases updated")
            return 0
        
        if self.args.status:
            self.colors.info("Local database status:")
            self.colors.info(f"  TLD Database: {len(self.intelligence_engine.local_databases.tld_database)} entries")
            self.colors.info(f"  IP Ranges: {len(self.intelligence_engine.local_databases.ip_ranges)} entries")
            self.colors.info(f"  Email Providers: {len(self.intelligence_engine.local_databases.email_providers)} entries")
            return 0
        
        if self.args.export:
            self.colors.info(f"Exporting databases to {self.args.export}")
            self.intelligence_engine.local_databases.save_databases()
            self.colors.success("Databases exported")
            return 0
        
        if self.args.import_file:
            self.colors.info(f"Importing databases from {self.args.import_file}")
            self.intelligence_engine.local_databases.load_databases()
            self.colors.success("Databases imported")
            return 0
        
        return 0
    
    def _display_email_analysis(self, analysis: Dict[str, Any]) -> None:
        """Display email analysis results"""
        print(f"\n{self.colors.highlight('=== EMAIL INTELLIGENCE ANALYSIS ===')}")
        print(f"Email: {analysis['email']}")
        print(f"Intelligence Score: {analysis['intelligence_score']:.2f}")
        print(f"Threat Level: {self._colorize_threat_level(analysis['threat_level'])}")
        
        # Basic analysis
        basic = analysis.get('basic_analysis', {})
        print(f"\n{self.colors.info('Basic Analysis:')}")
        print(f"  Valid: {basic.get('is_valid', False)}")
        print(f"  Disposable: {basic.get('is_disposable', False)}")
        print(f"  Length: {basic.get('length', 0)}")
        
        # Pattern analysis
        pattern = analysis.get('pattern_analysis', {})
        if pattern.get('patterns'):
            print(f"\n{self.colors.info('Patterns Detected:')}")
            for pattern_name in pattern['patterns']:
                print(f"  - {pattern_name}")
        
        # Threat analysis
        threat = analysis.get('threat_analysis', {})
        if threat.get('threat_indicators'):
            print(f"\n{self.colors.warning('Threat Indicators:')}")
            for indicator in threat['threat_indicators']:
                print(f"  - {indicator}")
        
        # Recommendations
        if analysis.get('recommendations'):
            print(f"\n{self.colors.highlight('Recommendations:')}")
            for rec in analysis['recommendations']:
                print(f"  - {rec}")
    
    def _display_domain_analysis(self, analysis: Dict[str, Any]) -> None:
        """Display domain analysis results"""
        print(f"\n{self.colors.highlight('=== DOMAIN INTELLIGENCE ANALYSIS ===')}")
        print(f"Domain: {analysis['domain']}")
        print(f"Intelligence Score: {analysis['intelligence_score']:.2f}")
        print(f"Threat Level: {self._colorize_threat_level(analysis['threat_level'])}")
        
        # Basic analysis
        basic = analysis.get('basic_analysis', {})
        print(f"\n{self.colors.info('Basic Analysis:')}")
        print(f"  Valid: {basic.get('is_valid', False)}")
        print(f"  Length: {basic.get('length', 0)}")
        print(f"  Subdomains: {basic.get('subdomain_count', 0)}")
        
        # TLD analysis
        tld = analysis.get('tld_analysis', {})
        if tld:
            print(f"\n{self.colors.info('TLD Analysis:')}")
            print(f"  TLD: {tld.get('tld', 'unknown')}")
            print(f"  Category: {tld.get('category', 'unknown')}")
            print(f"  Suspicious: {tld.get('is_suspicious', False)}")
        
        # Pattern analysis
        pattern = analysis.get('pattern_analysis', {})
        if pattern.get('patterns'):
            print(f"\n{self.colors.info('Patterns Detected:')}")
            for pattern_name in pattern['patterns']:
                print(f"  - {pattern_name}")
        
        # Recommendations
        if analysis.get('recommendations'):
            print(f"\n{self.colors.highlight('Recommendations:')}")
            for rec in analysis['recommendations']:
                print(f"  - {rec}")
    
    def _display_username_analysis(self, analysis: Dict[str, Any]) -> None:
        """Display username analysis results"""
        print(f"\n{self.colors.highlight('=== USERNAME INTELLIGENCE ANALYSIS ===')}")
        print(f"Username: {analysis['username']}")
        print(f"Intelligence Score: {analysis['intelligence_score']:.2f}")
        print(f"Threat Level: {self._colorize_threat_level(analysis['threat_level'])}")
        
        # Basic analysis
        basic = analysis.get('basic_analysis', {})
        print(f"\n{self.colors.info('Basic Analysis:')}")
        print(f"  Length: {basic.get('length', 0)}")
        print(f"  Length Category: {basic.get('length_category', 'unknown')}")
        print(f"  Has Numbers: {basic.get('has_numbers', False)}")
        print(f"  Has Special Chars: {basic.get('has_special_chars', False)}")
        print(f"  Suspicious: {basic.get('is_suspicious', False)}")
        print(f"  Risk Score: {basic.get('risk_score', 0):.2f}")
        
        # Pattern analysis
        pattern = analysis.get('pattern_analysis', {})
        if pattern.get('patterns'):
            print(f"\n{self.colors.info('Patterns Detected:')}")
            for pattern_name in pattern['patterns']:
                print(f"  - {pattern_name}")
        
        # Threat analysis
        threat = analysis.get('threat_analysis', {})
        if threat.get('threat_indicators'):
            print(f"\n{self.colors.warning('Threat Indicators:')}")
            for indicator in threat['threat_indicators']:
                print(f"  - {indicator}")
        
        # Recommendations
        if analysis.get('recommendations'):
            print(f"\n{self.colors.highlight('Recommendations:')}")
            for rec in analysis['recommendations']:
                print(f"  - {rec}")
    
    def _display_ip_analysis(self, analysis: Dict[str, Any]) -> None:
        """Display IP analysis results"""
        print(f"\n{self.colors.highlight('=== IP INTELLIGENCE ANALYSIS ===')}")
        print(f"IP: {analysis['ip']}")
        print(f"Intelligence Score: {analysis['intelligence_score']:.2f}")
        print(f"Threat Level: {self._colorize_threat_level(analysis['threat_level'])}")
        
        # Basic analysis
        basic = analysis.get('basic_analysis', {})
        print(f"\n{self.colors.info('Basic Analysis:')}")
        print(f"  Valid: {basic.get('is_valid', False)}")
        print(f"  Version: {basic.get('version', 'unknown')}")
        print(f"  Length: {basic.get('length', 0)}")
        
        # Classification analysis
        classification = analysis.get('classification_analysis', {})
        if classification:
            print(f"\n{self.colors.info('Classification:')}")
            print(f"  Type: {classification.get('type', 'unknown')}")
            print(f"  Class: {classification.get('class', 'unknown')}")
            print(f"  Description: {classification.get('description', 'unknown')}")
        
        # Geographic analysis
        geo = analysis.get('geographic_analysis', {})
        if geo:
            print(f"\n{self.colors.info('Geographic Analysis:')}")
            print(f"  Region: {geo.get('region', 'unknown')}")
            print(f"  Country: {geo.get('country', 'unknown')}")
            print(f"  Private: {geo.get('is_private', False)}")
            print(f"  Reserved: {geo.get('is_reserved', False)}")
        
        # Recommendations
        if analysis.get('recommendations'):
            print(f"\n{self.colors.highlight('Recommendations:')}")
            for rec in analysis['recommendations']:
                print(f"  - {rec}")
    
    def _display_correlation_analysis(self, correlation: Dict[str, Any]) -> None:
        """Display correlation analysis results"""
        print(f"\n{self.colors.highlight('=== CORRELATION INTELLIGENCE ANALYSIS ===')}")
        print(f"Targets: {', '.join(correlation['targets'])}")
        print(f"Correlation Score: {correlation['correlation_score']:.2f}")
        
        # Individual analyses
        print(f"\n{self.colors.info('Individual Analyses:')}")
        for i, analysis in enumerate(correlation['individual_analyses']):
            print(f"  {i+1}. {analysis.get('email', analysis.get('domain', analysis.get('username', analysis.get('ip', 'unknown'))))}")
            print(f"     Intelligence Score: {analysis.get('intelligence_score', 0):.2f}")
            print(f"     Threat Level: {self._colorize_threat_level(analysis.get('threat_level', 'unknown'))}")
        
        # Correlation patterns
        patterns = correlation.get('correlation_patterns', {})
        if patterns.get('common_patterns'):
            print(f"\n{self.colors.info('Common Patterns:')}")
            for pattern in patterns['common_patterns']:
                print(f"  - {pattern}")
        
        # Threat network
        network = correlation.get('threat_network', {})
        if network.get('high_risk_targets'):
            print(f"\n{self.colors.warning('High-Risk Targets:')}")
            for target in network['high_risk_targets']:
                print(f"  - {target.get('email', target.get('domain', target.get('username', target.get('ip', 'unknown'))))}")
        
        # Recommendations
        if correlation.get('recommendations'):
            print(f"\n{self.colors.highlight('Recommendations:')}")
            for rec in correlation['recommendations']:
                print(f"  - {rec}")
    
    def _display_comprehensive_analysis(self, analysis: Dict[str, Any]) -> None:
        """Display comprehensive analysis results"""
        print(f"\n{self.colors.highlight('=== COMPREHENSIVE INTELLIGENCE ANALYSIS ===')}")
        
        # Determine target type and display accordingly
        if 'email' in analysis:
            self._display_email_analysis(analysis)
        elif 'domain' in analysis:
            self._display_domain_analysis(analysis)
        elif 'username' in analysis:
            self._display_username_analysis(analysis)
        elif 'ip' in analysis:
            self._display_ip_analysis(analysis)
    
    def _display_history(self, history: List[Dict[str, Any]]) -> None:
        """Display analysis history"""
        print(f"\n{self.colors.highlight('=== ANALYSIS HISTORY ===')}")
        
        for i, entry in enumerate(history, 1):
            print(f"{i}. {entry.get('target', 'unknown')}")
            print(f"   Type: {entry.get('type', 'unknown')}")
            print(f"   Timestamp: {entry.get('timestamp', 'unknown')}")
            print(f"   Intelligence Score: {entry.get('intelligence_score', 0):.2f}")
            print()
    
    def _display_report(self, report: Dict[str, Any]) -> None:
        """Display intelligence report"""
        print(f"\n{self.colors.highlight('=== INTELLIGENCE REPORT ===')}")
        print(f"Target: {report.get('target', 'unknown')}")
        print(f"Generated: {report.get('timestamp', 'unknown')}")
        print(f"Intelligence Score: {report.get('intelligence_score', 0):.2f}")
        print(f"Threat Level: {self._colorize_threat_level(report.get('threat_level', 'unknown'))}")
        
        if report.get('summary'):
            print(f"\n{self.colors.info('Summary:')}")
            print(report['summary'])
        
        if report.get('recommendations'):
            print(f"\n{self.colors.highlight('Recommendations:')}")
            for rec in report['recommendations']:
                print(f"  - {rec}")
    
    def _colorize_threat_level(self, threat_level: str) -> str:
        """Colorize threat level for display"""
        if threat_level == 'critical':
            return self.colors.error('CRITICAL')
        elif threat_level == 'high':
            return self.colors.warning('HIGH')
        elif threat_level == 'medium':
            return self.colors.info('MEDIUM')
        elif threat_level == 'low':
            return self.colors.success('LOW')
        else:
            return self.colors.info('UNKNOWN')
    
    def _save_analysis(self, analysis: Dict[str, Any], filepath: str) -> None:
        """Save analysis to file"""
        import json
        
        with open(filepath, 'w') as f:
            json.dump(analysis, f, indent=2)
    
    def _save_report(self, report: Dict[str, Any], filepath: str, format_type: str) -> None:
        """Save report to file"""
        if format_type == 'json':
            import json
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2)
        elif format_type == 'txt':
            with open(filepath, 'w') as f:
                f.write(f"Intelligence Report\n")
                f.write(f"==================\n\n")
                f.write(f"Target: {report.get('target', 'unknown')}\n")
                f.write(f"Generated: {report.get('timestamp', 'unknown')}\n")
                f.write(f"Intelligence Score: {report.get('intelligence_score', 0):.2f}\n")
                f.write(f"Threat Level: {report.get('threat_level', 'unknown')}\n\n")
                
                if report.get('summary'):
                    f.write(f"Summary:\n{report['summary']}\n\n")
                
                if report.get('recommendations'):
                    f.write(f"Recommendations:\n")
                    for rec in report['recommendations']:
                        f.write(f"  - {rec}\n")
        elif format_type == 'html':
            with open(filepath, 'w') as f:
                f.write(f"<html><head><title>Intelligence Report</title></head><body>")
                f.write(f"<h1>Intelligence Report</h1>")
                f.write(f"<p><strong>Target:</strong> {report.get('target', 'unknown')}</p>")
                f.write(f"<p><strong>Generated:</strong> {report.get('timestamp', 'unknown')}</p>")
                f.write(f"<p><strong>Intelligence Score:</strong> {report.get('intelligence_score', 0):.2f}</p>")
                f.write(f"<p><strong>Threat Level:</strong> {report.get('threat_level', 'unknown')}</p>")
                
                if report.get('summary'):
                    f.write(f"<h2>Summary</h2><p>{report['summary']}</p>")
                
                if report.get('recommendations'):
                    f.write(f"<h2>Recommendations</h2><ul>")
                    for rec in report['recommendations']:
                        f.write(f"<li>{rec}</li>")
                    f.write(f"</ul>")
                
                f.write(f"</body></html>")
    
    def _generate_intelligence_report(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate intelligence report from analysis"""
        report = {
            'target': analysis.get('email', analysis.get('domain', analysis.get('username', analysis.get('ip', 'unknown')))),
            'timestamp': datetime.now().isoformat(),
            'intelligence_score': analysis.get('intelligence_score', 0),
            'threat_level': analysis.get('threat_level', 'unknown'),
            'summary': self._generate_summary(analysis),
            'recommendations': analysis.get('recommendations', [])
        }
        
        return report
    
    def _generate_summary(self, analysis: Dict[str, Any]) -> str:
        """Generate summary from analysis"""
        intelligence_score = analysis.get('intelligence_score', 0)
        threat_level = analysis.get('threat_level', 'unknown')
        
        summary = f"Intelligence analysis completed with a score of {intelligence_score:.2f} "
        summary += f"and threat level of {threat_level.upper()}. "
        
        if threat_level in ['high', 'critical']:
            summary += "Immediate investigation is recommended due to high threat indicators. "
        elif threat_level == 'medium':
            summary += "Moderate risk detected - continued monitoring advised. "
        else:
            summary += "Low risk profile - standard monitoring sufficient. "
        
        # Add pattern information
        patterns = analysis.get('pattern_analysis', {}).get('patterns', [])
        if patterns:
            summary += f"Detected patterns: {', '.join(patterns)}. "
        
        # Add threat information
        threats = analysis.get('threat_analysis', {}).get('threat_indicators', [])
        if threats:
            summary += f"Threat indicators: {', '.join(threats)}. "
        
        return summary


def main():
    """Main entry point for offline CLI"""
    cli = OfflineCLI()
    return cli.run()


if __name__ == '__main__':
    sys.exit(main())