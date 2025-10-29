from unittest.mock import patch, Mock

from osint_cli.main import email_command, domain_command, ip_command, social_command


class TestPreferOfflineConfig:
    def test_email_prefers_offline_from_config(self):
        args = Mock()
        args.target = 'user@example.com'
        args.offline = False
        args.online = False
        with patch('osint_cli.main.load_config', return_value={'preferences': {'prefer_offline': True}}), \
             patch('osint_cli.core.offline_intelligence.OfflineIntelligenceEngine') as mock_engine_class, \
             patch('osint_cli.main.Reporter') as mock_reporter_class:
            engine = Mock()
            engine.analyze_email_intelligence.return_value = {'email': 'user@example.com'}
            mock_engine_class.return_value = engine
            rc = email_command(args)
            assert rc == 0
            engine.analyze_email_intelligence.assert_called_once_with('user@example.com')

    def test_domain_prefers_offline_from_config(self):
        args = Mock()
        args.target = 'example.com'
        args.offline = False
        args.online = False
        with patch('osint_cli.main.load_config', return_value={'preferences': {'prefer_offline': True}}), \
             patch('osint_cli.core.offline_intelligence.OfflineIntelligenceEngine') as mock_engine_class, \
             patch('osint_cli.main.Reporter') as mock_reporter_class:
            engine = Mock()
            engine.analyze_domain_intelligence.return_value = {'domain': 'example.com'}
            mock_engine_class.return_value = engine
            rc = domain_command(args)
            assert rc == 0
            engine.analyze_domain_intelligence.assert_called_once_with('example.com')

    def test_ip_prefers_offline_from_config(self):
        args = Mock()
        args.target = '8.8.8.8'
        args.offline = False
        args.online = False
        with patch('osint_cli.main.load_config', return_value={'preferences': {'prefer_offline': True}}), \
             patch('osint_cli.core.offline_intelligence.OfflineIntelligenceEngine') as mock_engine_class, \
             patch('osint_cli.main.Reporter') as mock_reporter_class:
            engine = Mock()
            engine.analyze_ip_intelligence.return_value = {'ip': '8.8.8.8'}
            mock_engine_class.return_value = engine
            rc = ip_command(args)
            assert rc == 0
            engine.analyze_ip_intelligence.assert_called_once_with('8.8.8.8')

    def test_social_prefers_offline_from_config(self):
        args = Mock()
        args.username = 'john_doe'
        args.offline = False
        args.online = False
        with patch('osint_cli.main.load_config', return_value={'preferences': {'prefer_offline': True}}), \
             patch('osint_cli.core.offline_intelligence.OfflineIntelligenceEngine') as mock_engine_class, \
             patch('osint_cli.main.Reporter') as mock_reporter_class:
            engine = Mock()
            engine.analyze_username_intelligence.return_value = {'username': 'john_doe'}
            mock_engine_class.return_value = engine
            rc = social_command(args)
            assert rc == 0
            engine.analyze_username_intelligence.assert_called_once_with('john_doe')
