import json
from unittest.mock import patch, Mock
from pathlib import Path

from osint_cli.main import config_command
from osint_cli.config import load_config, save_default_config, DEFAULT_CONFIG


class TestConfigCLI:
    def test_config_init_success(self):
        args = Mock()
        args.init = True
        args.show = False
        args.path = "/tmp/osint_cli_test_config.json"
        with patch("builtins.open", create=True) as mock_open, \
             patch("pathlib.Path.mkdir") as mock_mkdir:
            rc = config_command(args)
            assert rc == 0
            mock_open.assert_called_once()

    def test_config_show_success(self):
        args = Mock()
        args.init = False
        args.show = True
        args.path = "/tmp/osint_cli_test_config.json"
        with patch("pathlib.Path.exists", return_value=True), \
             patch("builtins.open", create=True) as mock_open, \
             patch("builtins.print") as mock_print:
            mock_open.return_value.__enter__.return_value.read.return_value = json.dumps(DEFAULT_CONFIG)
            rc = config_command(args)
            assert rc == 0
            mock_print.assert_called_once()

    def test_config_neither_flag(self):
        args = Mock()
        args.init = False
        args.show = False
        args.path = None
        with patch("builtins.print") as mock_print:
            rc = config_command(args)
            assert rc == 1
            assert mock_print.call_count == 1


class TestConfigModule:
    def test_load_config_defaults_when_missing(self):
        with patch("pathlib.Path.exists", return_value=False):
            cfg = load_config("/nonexistent.json")
            assert cfg["preferences"]["report_format"] == DEFAULT_CONFIG["preferences"]["report_format"]

    def test_load_config_merges_with_defaults(self):
        user_cfg = {"preferences": {"report_format": "html"}}
        with patch("pathlib.Path.exists", return_value=True), \
             patch("builtins.open", create=True) as mock_open:
            mock_open.return_value.__enter__.return_value.read.return_value = json.dumps(user_cfg)
            cfg = load_config("/tmp/custom.json")
            assert cfg["preferences"]["report_format"] == "html"
            # Retains default keys too
            assert "color_output" in cfg["preferences"]

    def test_save_default_config(self):
        with patch("builtins.open", create=True) as mock_open, \
             patch("pathlib.Path.mkdir") as mock_mkdir:
            path = save_default_config("/tmp/osint_cli_default.json")
            assert str(path).endswith("/tmp/osint_cli_default.json")
            mock_open.assert_called_once()
